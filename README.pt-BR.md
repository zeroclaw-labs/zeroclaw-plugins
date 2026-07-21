# Safe Hands — autorização de transações Solana para agentes autônomos

**O agente propõe. O Safe Hands decide. Um humano (ou multisig) dispõe.**

Safe Hands é um conjunto de três plugins para o ZeroClaw que fica entre o
agente de IA e dinheiro real na Solana. Ele decodifica qualquer transação não
assinada até o nível de instrução, confere a intenção declarada e a política
de gastos do operador, simula a transação e emite um veredito —
**ALLOW / REVIEW / DENY / UNKNOWN** — com códigos de motivo legíveis por
máquina. O que precisar de humano vira uma proposta de multisig Squads v4 não
assinada, construída somente depois que o proponente **refaz sozinho toda a
avaliação de política** — um "ALLOW" fornecido pelo chamador nunca é confiável.

## Um comando prova tudo

```bash
just prove-safety
```

Offline, sem toolchain wasm, sem rede: todos os testes unitários, a **arena de
20 ataques** (fixtures YAML rodando contra os plugins reais), `clippy
-D warnings` no host **e** no alvo `wasm32-wasip2`, e builds de release dos
três componentes.

## Níveis de custódia

| Componente | Nível | Segredos |
|---|---|---|
| solana-tx-authorize | **T0** | Chave RPC no máximo. Não constrói nada, não guarda nada. |
| spl-transfer-build | **T1** | Nenhum. Saída não assinada. |
| squads-proposal-build | **T1** | Nenhum. Proposta não assinada. |

Não existe caminho de assinatura em nenhum lugar. O padrão favorito do bounty
— *o agente propõe, a multisig dispõe* — é o fluxo padrão.

## Fluxo de um pagamento

```
 "cobre a mesa 4: 25 USDC, fatura 412"
        ▼
 spl-transfer-build     → transação não assinada + intenção declarada
        ▼
 solana-tx-authorize    → decodifica → intenção → política → simulação
                        → ALLOW / REVIEW / DENY / UNKNOWN
        ▼
 squads-proposal-build  → re-autorização INDEPENDENTE → proposta Squads v4
        ▼
 Humano aprova no celular → a multisig executa
 (o agente nunca segurou uma chave)
```

## Configuração (5 minutos)

```bash
just wasm
zeroclaw plugin install ./plugins/solana-tx-authorize
zeroclaw plugin install ./plugins/spl-transfer-build
zeroclaw plugin install ./plugins/squads-proposal-build
# depois copie examples/zeroclaw-config.demo.toml para ~/.zeroclaw/config.toml
```

Sem banco de dados, sem backend, sem Docker.

## Verificado de ponta a ponta na devnet

O fluxo completo rodou ao vivo com um agente ZeroClaw real, componentes reais
e uma multisig Squads real na devnet: proposta enviada, aprovada e executada
— 0,05 SOL movidos do vault. Assinaturas em [EVIDENCE.md](EVIDENCE.md).

## Nota sobre memos PIX/BRL

Os memos de fatura (`memo`) são apenas metadados contábeis para reconciliação.
O Safe Hands não executa PIX, câmbio, liquidação internacional ou conversão
entre BRL e stablecoins.

Documentação completa em inglês: [README.md](README.md) · Licença MIT · Feito
para o bounty ZeroClaw × Solana (Superteam Brasil) 🇧🇷
