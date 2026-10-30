// bip54-xcheck runner for btcd. CI copies this file into btcd's blockchain
// package (so it can use chainSetup) and runs:
//
//	XCHECK_CASES=cases.json XCHECK_OUT=btcd.json go test -run TestXcheck ./blockchain
//
// Each case is replayed on a fresh chain: the case's base chain, then the
// case blocks through ProcessBlock. The first block that is not accepted as
// the new tip ends the case.

package blockchain

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
)

type xcheckCase struct {
	ID     string   `json:"id"`
	Base   string   `json:"base"`
	Blocks []string `json:"blocks"`
}

type xcheckDoc struct {
	Bases map[string][]string `json:"bases"`
	Cases []xcheckCase        `json:"cases"`
}

type xcheckResult struct {
	Verdict string `json:"verdict"`
	At      *int   `json:"at"`
	Reason  string `json:"reason"`
}

// xcheckParams mirrors Bitcoin Core PR #35793's regtest: BIP-54 always
// active ("always"), or deployed with BIP9 on bit 3 with Core's regtest
// window of 144 and threshold of 108 ("vbits", as -vbparams sets it).
func xcheckParams(base string) *chaincfg.Params {
	params := chaincfg.RegressionNetParams
	d := params.Deployments[chaincfg.DeploymentBIP54]
	switch base {
	case "always":
		d.AlwaysActiveHeight = 1
	default:
		d.BitNumber = 3
		d.AlwaysActiveHeight = 0
		d.DeploymentStarter = chaincfg.NewMedianTimeDeploymentStarter(time.Time{})
		d.DeploymentEnder = chaincfg.NewMedianTimeDeploymentEnder(time.Time{})
	}
	params.Deployments[chaincfg.DeploymentBIP54] = d
	return &params
}

func xcheckProcess(chain *BlockChain, hexBlock string) error {
	raw, err := hex.DecodeString(hexBlock)
	if err != nil {
		return fmt.Errorf("hex: %w", err)
	}
	block, err := btcutil.NewBlockFromBytes(raw)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	isMain, isOrphan, err := chain.ProcessBlock(block, BFNone)
	switch {
	case err != nil:
		var rerr RuleError
		if errors.As(err, &rerr) {
			return fmt.Errorf("%s: %s", rerr.ErrorCode, rerr.Description)
		}
		return err
	case isOrphan:
		return errors.New("orphan")
	case !isMain:
		return errors.New("not-main-chain")
	}
	return nil
}

func TestXcheck(t *testing.T) {
	in, out := os.Getenv("XCHECK_CASES"), os.Getenv("XCHECK_OUT")
	if in == "" || out == "" {
		t.Skip("XCHECK_CASES / XCHECK_OUT not set")
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	var doc xcheckDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	results := map[string]xcheckResult{}
	for _, c := range doc.Cases {
		chain, teardown, err := chainSetup("xcheck_"+c.ID, xcheckParams(c.Base))
		if err != nil {
			t.Fatalf("%s: chainSetup: %v", c.ID, err)
		}
		for i, b := range doc.Bases[c.Base] {
			if err := xcheckProcess(chain, b); err != nil {
				teardown()
				t.Fatalf("%s: base block %d rejected: %v", c.ID, i+1, err)
			}
		}
		res := xcheckResult{Verdict: "valid"}
		for i, b := range c.Blocks {
			if err := xcheckProcess(chain, b); err != nil {
				at := i
				res = xcheckResult{Verdict: "invalid", At: &at, Reason: err.Error()}
				break
			}
		}
		teardown()
		results[c.ID] = res
		t.Logf("%s: %s %s", c.ID, res.Verdict, res.Reason)
	}

	enc, _ := json.MarshalIndent(results, "", "  ")
	if err := os.WriteFile(out, enc, 0o644); err != nil {
		t.Fatal(err)
	}
}
