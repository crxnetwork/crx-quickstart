# BUILD JOURNAL — arm-fix-alloc-sealer (BUILDER T3)

Worktree: /private/tmp/crx-arm-fix-client
Branch: arm-fix-alloc-sealer  (base 25e1041 origin/main)
Task: build alloc + closeout sealed-envelope producers (FIX 2). CSPRNG-salt discipline mirror of OpenSide. DO NOT PUSH.

## Log
- fetch origin OK. origin/main=25e1041 (has arm_seal.py). local main c558279 = 3 behind (no sealer). Confirmed.
- worktree add -b arm-fix-alloc-sealer @ 25e1041 OK.
- venv py3.9.6, pip install requirements OK, + pytest.
- BASELINE: `pytest test_arm_seal.py -q` => 11 passed in 6.05s. GREEN.
- Neither /private/tmp/crx-mono-p5 (Rust submitter) nor /private/tmp/crx-arm-encrypt (fixture) present locally.
  => cannot read submitter body shape ground truth. Mirror build_open_side_sealed EXACTLY; document assumptions.
  => test_fixture_on_disk_matches_hardcoded self-skips (path absent) — as in baseline.

## Assumptions (submitter body shape — could not verify against Rust)
- public dict: bytes32 -> "0x"+hex, address -> _addr, nonce/openNonce (uint64) -> str (JS-safe, mirror open_side nonce->str), deadline (uint64 timestamp) -> int (mirror open_side quoteExpiry->int).
- witness key = "item" (task point 6). open_side used "leg". Wide amount/id/nonce fields -> str; small bps/side/instrumentId and timestamps -> int. Witness is defence-in-depth, NOT in the commitment; typing is cosmetic.
- closeout consent digest = failover_consent_digest (:265) — its FailoverConsent fields (oldId,closedOutSide,remainingSide,incoming,incomingSide,nonce,openNonce,deadline) match CLOSE public exactly.
- allocation consent digest = allocation_consent_digest (:237). allocation_acceptance_digest (:247) is the 2nd-signer/taker path — NOT used by the maker's own consent half-arm (mirrors open_side single-seat sign).
- crx_maker wrappers take a pre-built full item dict + chain key (no rfq->alloc field-map spec exists). chain_id/domain derived like open_side.

## RESULT
- FULL pytest: 21 passed in 0.43s (11 baseline + 10 new).
- positive control: commit_alloc(weak) computes fine; builder GUARD raises ValueError. Confirmed both directions.
- committed 14484f1 on arm-fix-alloc-sealer. NOT pushed. worktree left for gating.

## FIX 2b — adversarial interop breaks (read Rust @ /Users/maxguillabert/.crxfx-cd/repo d34c1052)
- BREAK A (allocation): AllocationSealedRequest (allocation.rs:90-111) requires exitingSeat, remainingSeat, sigs:Vec — NOT singular sig. Multi-signature. Mode = incomingSide==remainingSide.
  - REDESIGNED build_allocation_sealed(chain_id, domain, item, signers, enc_keys, exiting_seat, remaining_seat, salt, include_witness).
  - signers = dict of per-role digest-signers. Choreography (allocation.rs:227-259):
    * plain close: sigs=[exiting, remaining] BOTH over allocation_consent_digest; client sets incoming==remainingSeat.
    * allocation: sigs=[exiting→consent, incoming→acceptance, remaining→voluntary_open_consent(openNonce,deadline)].
  - Returns (body, consent) — exiting consent is the primary/relayed digest.
  - crx_maker.arm_allocation_sealed reworked: takes signers map + seat addrs; added _key_signer(acct) helper.
- BREAK B (closeout): singular `sig` was already correct. ONLY bug: witness closeTime was int; WireCloseoutItem.close_time is String (liq_rfq.rs:51, parse_u64:122). Fixed -> str(item["closeTime"]).
- Added 2 WIRE-interop tests asserting every Rust request-struct field present w/ correct JSON type (str/int/0xhex), + plain-close 2-sig test. Digests recover the declared signers.
- FULL pytest: 24 passed in 1.53s. py_compile both modules OK.
- NO OTHER field-type drift: audited alloc/closeout public + witness field-by-field vs Wire* structs — all match.
