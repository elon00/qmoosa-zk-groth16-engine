# QMOOSA Zero-Knowledge Cryptography — Groth16 Engine

Cryptographic verification engine implementing BN254 / Alt-bn128 optimal ate pairings, public input linear combination accumulation, and Groth16 pairing equality checks using audited `@noble/curves`.

## Verification Equation
$$e(A, B) = e(\alpha_1, \beta_2) \cdot e(L, \gamma_2) \cdot e(C, \delta_2)$$
where $L = IC_0 + \sum_{i=1}^l x_i \cdot IC_i \in G_1$.

## Security Governance
- **Zero Cloud Spend Invariant**: $0.00 spent across all cloud and blockchain resources.
- **Production Certification Lock**: Mainnet/public testnets strictly locked at `0 / 1,000 CERTIFIED`.

## Build & Test
```bash
npm install
npm run build
npm test
npm run lint
```
