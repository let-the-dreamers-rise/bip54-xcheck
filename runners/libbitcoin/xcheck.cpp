// bip54-xcheck runner for libbitcoin-system (the consensus library of libbitcoin node).
//
// Reads a flat case file produced by runners/libbitcoin/flatten.py:
//   BASE <name>         start a new base chain on top of regtest genesis
//   B <hex>             a block (base block, or case block after CASE)
//   CASE <id>           replay the following blocks on top of the current base tip
// Prints one line per case: <id> <valid|invalid> <index|-> <reason>
//
// Each block goes through the same steps libbitcoin-node uses for a candidate block:
// header check + accept (context from chain_state), block check (context free and
// contextual), prevout population from a UTXO set, accept, connect (scripts).

#include <bitcoin/system.hpp>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace bc::system;
using namespace bc::system::chain;

struct utxo { output::cptr out; size_t height; bool coinbase; uint32_t mtp; };
using utxo_set = std::map<std::pair<hash_digest, uint32_t>, utxo>;

struct tip
{
    std::shared_ptr<chain_state> state;
    utxo_set utxos;
};

static settings make_settings(bool vbits)
{
    settings s{ selection::regtest };
    if (vbits)
    {
        // Match Bitcoin Core #35793 regtest with -vbparams=consensuscleanup:0:9999999999:
        // one BIP9 deployment on bit 3, period 144, threshold 108, start 0, no timeout.
        // libbitcoin models BIP-54 as five deployments (bits 5-9); put all five on bit 3.
        s.bip9_activation_period = 144;
        for (auto* d: { &s.bip54_timewarp_deployment, &s.bip54_timespan_deployment,
            &s.bip54_sigops_deployment, &s.bip54_txsize_deployment,
            &s.bip54_coinbase_deployment })
        {
            d->bit = 3;
            d->start = 0;
            d->timeout = bc::max_uint32;
            d->threshold = 108;
            d->activation_height = 0;
            d->speedy = false;
        }
    }
    // Match Bitcoin Core regtest: BIP34 enforced from height 1 (Core's BIP34Height = 1).
    s.forks.bip34 = true;
    s.forks.bip90 = true;
    s.bip90_bip34_height = 1;
    return s;
}

static std::shared_ptr<chain_state> genesis_state(const settings& s)
{
    const auto& g = s.genesis_block.header();
    chain_state::data d{};
    d.height = 0;
    d.hash = g.hash();
    d.bits.self = g.bits();
    d.version.self = g.version();
    d.timestamp.self = g.timestamp();
    d.timestamp.retarget = g.timestamp();
    d.cumulative_work = g.proof();
    return std::make_shared<chain_state>(std::move(d), s);
}

// Returns empty string on success, else the reason.
static std::string apply(tip& t, const data_chunk& raw, const settings& s)
{
    const block blk{ raw, true };
    if (!blk.is_valid())
        return "deserialize";
    const auto& head = blk.header();
    if (head.previous_block_hash() != t.state->hash())
        return "orphan";

    auto next = std::make_shared<chain_state>(*t.state, head, s);
    const auto ctx = next->context();

    if (const auto ec = head.check(s.timestamp_limit_seconds, s.proof_of_work_limit,
        s.forks.ltc_scrypt_proof_of_work))
        return "header.check: " + ec.message();
    if (const auto ec = head.accept(ctx, s.retargeting_interval()))
        return "header.accept: " + ec.message();
    if (const auto ec = blk.check())
        return "block.check: " + ec.message();
    if (const auto ec = blk.check(ctx))
        return "block.check(ctx): " + ec.message();

    // Populate prevouts from the UTXO set (outputs created in this block are
    // handled by block::populate).
    auto spent = t.utxos;
    for (const auto& tx: *blk.transactions_ptr())
    {
        if (tx->is_coinbase())
            continue;
        for (const auto& in: *tx->inputs_ptr())
        {
            const auto it = spent.find({ in->point().hash(), in->point().index() });
            if (it == spent.end())
                continue;
            in->prevout = it->second.out;
            in->metadata.coinbase = it->second.coinbase;
            in->metadata.prevout_height = it->second.height;
            in->metadata.median_time_past = it->second.mtp;
        }
    }
    if (const auto ec = blk.populate(ctx))
        return "block.populate: " + ec.message();
    if (const auto ec = blk.accept(ctx, s.subsidy_interval_blocks, s.initial_subsidy()))
        return "block.accept: " + ec.message();
    if (const auto ec = blk.connect(ctx))
        return "block.connect: " + ec.message();
    if (const auto ec = blk.confirm(ctx))
        return "block.confirm: " + ec.message();

    // Update UTXO set.
    for (const auto& tx: *blk.transactions_ptr())
    {
        if (!tx->is_coinbase())
            for (const auto& in: *tx->inputs_ptr())
                spent.erase({ in->point().hash(), in->point().index() });
        const auto id = tx->hash(false);
        uint32_t index{};
        for (const auto& out: *tx->outputs_ptr())
            spent[{ id, index++ }] = { out, ctx.height, tx->is_coinbase(), ctx.median_time_past };
    }
    t.utxos = std::move(spent);
    t.state = next;
    return {};
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "usage: xcheck <flat-cases> [vbits]\n";
        return 2;
    }

    const auto s = make_settings(argc > 2 && std::string{ argv[2] } == "vbits");
    std::ifstream file{ argv[1] };
    std::string line, base_name, case_id;
    tip base{}, work{};
    bool in_case{ false };
    bool failed{ false };
    size_t index{};
    std::string reason;
    size_t fail_at{};

    const auto finish = [&]()
    {
        if (!in_case)
            return;
        if (failed)
            std::cout << case_id << " invalid " << fail_at << " " << reason << "\n";
        else
            std::cout << case_id << " valid - \n";
        in_case = false;
    };

    while (std::getline(file, line))
    {
        if (line.rfind("BASE ", 0) == 0)
        {
            finish();
            base_name = line.substr(5);
            base = { genesis_state(s), {} };
        }
        else if (line.rfind("CASE ", 0) == 0)
        {
            finish();
            case_id = line.substr(5);
            work = base;
            in_case = true;
            failed = false;
            index = 0;
        }
        else if (line.rfind("B ", 0) == 0)
        {
            data_chunk raw{};
            if (!decode_base16(raw, line.substr(2)))
            {
                std::cerr << "bad hex\n";
                return 1;
            }
            if (!in_case)
            {
                const auto r = apply(base, raw, s);
                if (!r.empty())
                {
                    std::cerr << base_name << ": base block " << base.state->height() + 1
                        << " rejected: " << r << "\n";
                    return 1;
                }
            }
            else if (!failed)
            {
                const auto r = apply(work, raw, s);
                if (!r.empty())
                {
                    failed = true;
                    fail_at = index;
                    reason = r;
                }
                ++index;
            }
        }
    }
    finish();
    return 0;
}
