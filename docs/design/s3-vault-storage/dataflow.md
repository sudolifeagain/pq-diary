# S3: Vault フォーマット + ストレージ — データフロー図

> **スプリント**: S3 (s3-vault-storage)
> **ステータス**: 全項目 DECIDED

---

## 1. Vault 初期化フロー

CLI から `init` コマンドが呼ばれた際の処理フロー。
VaultManager がディレクトリ作成・鍵生成・ファイル書き出しを統括する。

```mermaid
sequenceDiagram
    participant CLI
    participant VM as VaultManager
    participant CE as CryptoEngine
    participant W as vault/writer.rs

    CLI->>VM: init_vault("private", password)
    VM->>VM: mkdir ~/.pq-diary/vaults/private/
    VM->>CE: Argon2id(password, random_salt)
    CE-->>VM: sym_key
    VM->>CE: ML-KEM keygen()
    CE-->>VM: (ek, dk)
    VM->>CE: ML-DSA keygen()
    CE-->>VM: (vk, sk)
    VM->>CE: AES-GCM encrypt(sym_key, random_32B_token)
    CE-->>VM: verification_token
    VM->>W: write_vault(header, empty_entries)
    W-->>VM: vault.pqd created
    VM->>VM: write vault.toml (serde serialize)
    VM->>VM: mkdir entries/
    VM-->>CLI: Ok(())
```

### 処理ステップ詳細

1. `VaultManager::init_vault()` がディレクトリ `~/.pq-diary/vaults/{name}/` を作成
2. `CryptoEngine` で Argon2id KDF を実行し、パスワードから対称鍵を導出
3. ML-KEM-768 鍵ペア (カプセル化鍵 `ek` / 脱カプセル化鍵 `dk`) を生成
4. ML-DSA-65 鍵ペア (検証鍵 `vk` / 署名鍵 `sk`) を生成
5. ランダム 32 バイトトークンを AES-256-GCM で暗号化し、検証トークンとする
6. `write_vault()` でヘッダ + 空エントリセクション + パディングを vault.pqd に書き出し
7. vault.toml をデフォルト設定で生成
8. `entries/` サブディレクトリを作成

---

## 2. vault.pqd 読み込みフロー

ファイルオープンからヘッダ検証、エントリレコード逐次読み込みまでのフロー。

```mermaid
flowchart TD
    READ[ファイル読み込み] --> MAGIC{マジックバイト検証}
    MAGIC -->|"PQDIARY\0" 一致| VER{バージョン検証}
    MAGIC -->|不一致| ERR1[DiaryError::Vault<br/>不正なファイル形式]
    VER -->|0x04| HEADER[ヘッダパース<br/>204B 固定部分]
    VER -->|その他| ERR2[DiaryError::Vault<br/>未対応バージョン]
    HEADER --> SKBLOCK[秘密鍵ブロック読み込み<br/>可変長]
    SKBLOCK --> ENTRIES[エントリセクション開始]
    ENTRIES --> RECORD{レコード長読み込み<br/>4B LE u32}
    RECORD -->|"> 0"| PARSE[レコードパース<br/>UUID, IV, 暗号文, 署名...]
    PARSE --> VALIDATE[HMAC 検証]
    VALIDATE --> ENTRIES
    RECORD -->|"= 0"| PAD[パディング読み飛ばし]
    PAD --> DONE[読み込み完了<br/>VaultHeader + Vec of EntryRecord]
```

### エラーハンドリング

| エラー条件 | エラー型 | 説明 |
|-----------|---------|------|
| マジックバイト不一致 | `DiaryError::Vault` | vault.pqd でないファイルを開いた場合 |
| バージョン不一致 | `DiaryError::Vault` | 未対応のスキーマバージョン |
| ヘッダサイズ不足 | `DiaryError::Vault` | ファイルが途中で切れている場合 |
| レコード長異常 | `DiaryError::Vault` | レコード長がファイル残りを超える場合 |
| HMAC 検証失敗 | `DiaryError::Integrity` | レコードが改竄された場合 |

---

## 3. vault.toml / config.toml パースフロー

serde + toml クレートによる設定ファイルの読み書きフロー。

```mermaid
flowchart TD
    subgraph "vault.toml パース"
        VR[ファイル読み込み<br/>fs::read_to_string] --> VP[toml::from_str&lt;VaultConfig&gt;]
        VP -->|Ok| VC[VaultConfig 構造体]
        VP -->|Err| VE[DiaryError::Config<br/>パースエラー]
    end

    subgraph "config.toml パース"
        CR[ファイル読み込み<br/>fs::read_to_string] --> CP[toml::from_str&lt;AppConfig&gt;]
        CP -->|Ok| CC[AppConfig 構造体]
        CP -->|Err| CE2[DiaryError::Config<br/>パースエラー]
    end

    subgraph "vault.toml 書き込み"
        WS[VaultConfig 構造体] --> WT[toml::to_string_pretty]
        WT --> WF[fs::write<br/>vault.toml]
    end
```

### 設定ファイルパス

| ファイル | パス | 用途 |
|---------|------|------|
| config.toml | `~/.pq-diary/config.toml` | アプリケーション全体設定 (デフォルト Vault、デーモン設定) |
| vault.toml | `~/.pq-diary/vaults/{name}/vault.toml` | Vault 固有設定 (アクセスポリシー、Git 設定、Argon2 パラメータ) |

---

## 4. エントリ追加フロー

新規日記エントリを Vault に追加する際の暗号化・書き込みフロー。

```mermaid
sequenceDiagram
    participant CLI
    participant VM as VaultManager
    participant CE as CryptoEngine
    participant R as vault/reader.rs
    participant W as vault/writer.rs

    CLI->>VM: add_entry(vault_name, plaintext)
    VM->>R: read_vault(vault.pqd)
    R-->>VM: (header, entries)
    VM->>CE: AES-GCM encrypt(sym_key, plaintext)
    CE-->>VM: (iv, ciphertext)
    VM->>CE: ML-DSA sign(sk, ciphertext)
    CE-->>VM: signature
    VM->>CE: HMAC-SHA256(key, record_data)
    CE-->>VM: hmac
    VM->>VM: EntryRecord 構築
    VM->>W: write_vault(header, entries + new_entry)
    W-->>VM: vault.pqd updated
    VM-->>CLI: Ok(uuid)
```

---

## 5. マルチ Vault ディレクトリ構造

```
~/.pq-diary/
  config.toml                          # アプリ全体設定
  vaults/
    private/                           # Vault "private"
      vault.pqd                        # バイナリ Vault ファイル
      vault.toml                       # Vault 設定
      entries/                         # エントリ個別ファイル (将来拡張)
      .git/                            # Git リポジトリ
    work/                              # Vault "work"
      vault.pqd
      vault.toml
      entries/
      .git/
```
