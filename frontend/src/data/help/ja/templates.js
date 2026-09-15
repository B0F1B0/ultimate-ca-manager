export default {
  helpContent: {
    title: '証明書テンプレート',
    subtitle: '再利用可能な証明書プロファイル',
    overview: 'サブジェクトフィールド、Key Usage、Extended Key Usage、有効期間、その他の拡張が事前設定された再利用可能な証明書プロファイルを定義します。証明書の発行または署名時にテンプレートを適用します。',
    sections: [
      {
        title: 'テンプレートタイプ',
        definitions: [
          { term: 'エンドエンティティ', description: 'サーバー、クライアント、コード署名、メール証明書用' },
          { term: 'CA', description: '中間CA作成用' },
        ]
      },
      {
        title: '機能',
        items: [
          { label: 'サブジェクトデフォルト', text: '組織、OU、国、都道府県、市区町村を事前入力' },
          { label: 'Key Usage', text: 'Digital Signature、Key Enciphermentなど' },
          { label: 'Extended Key Usage', text: 'Server Auth、Client Auth、Code Signing、Email Protection' },
          { label: '有効期間', text: 'デフォルトの有効期間（日数）' },
          { label: '複製', text: '既存のテンプレートをクローンして修正' },
          { label: 'インポート/エクスポート', text: 'UCMインスタンス間でテンプレートをJSONファイルとして共有' },
        ]
      },
      {
        title: 'Windows自動登録',
        items: [
          { label: '自動登録を許可', text: '証明書登録ポリシーでテンプレートをautoEnroll=trueとして公開し、GPO/Kerberosクライアントがログオン時に自動的に要求できるようにします。デフォルトは無効, 無効でも手動登録は引き続き可能です' },
          { label: 'Active Directoryからサブジェクトを構築', text: 'クライアントに指定を要求する代わりに、要求元のADオブジェクトから（ADコネクタ経由で）サブジェクトとSANを導出します, 無人のGPO自動登録向け' },
          { label: '登録をADグループに制限', text: '設定されたADグループのメンバー（ネストされたメンバーシップを含む）のみがKerberosエンドポイント経由で登録できます。空欄 = 認証済みプリンシパル全員。ユーザー名/パスワードエンドポイントには適用されません' },
          { label: '固定サブジェクトフィールド', text: 'WSTEP経由で発行されるすべての証明書にC/ST/L/O/OUの値を強制し、これらのフィールドについてCSRやAD導出を上書きします。CNとSANは影響を受けません, 動的のままにするにはフィールドを空欄にしてください' },
        ]
      },
    ],
    tips: [
      'TLSサーバー、クライアント、コード署名用に別々のテンプレートを作成してください',
      '複製アクションを使用してテンプレートのバリエーションをすばやく作成できます',
      '自動登録フラグ付きのテンプレートは、一覧にAD / Auto / ACL / Pinnedバッジを表示します',
    ],
  },
  helpGuides: {
    title: '証明書テンプレート',
    content: `
## 概要

テンプレートは再利用可能な証明書プロファイルを定義します。毎回Key Usage、Extended Key Usage、有効期間、サブジェクトフィールドを手動で設定する代わりに、テンプレートを適用してすべてを事前入力します。

## テンプレートタイプ

### エンドエンティティテンプレート
サーバー証明書、クライアント証明書、コード署名、メール保護用。これらのテンプレートは通常以下を設定します：
- **Key Usage**: Digital Signature、Key Encipherment
- **Extended Key Usage**: Server Auth、Client Auth、Code Signing、Email Protection

### CAテンプレート
中間CA作成用。以下を設定します：
- **Key Usage**: Certificate Sign、CRL Sign
- **Basic Constraints**: CA:TRUE、オプションのパス長

## テンプレートの作成

1. **テンプレートを作成**をクリック
2. **名前**とオプションの説明を入力
3. テンプレート**タイプ**を選択（エンドエンティティまたはCA）
4. **サブジェクトデフォルト**を設定（O、OU、C、ST、L）
5. **Key Usage**フラグを選択
6. **Extended Key Usage**値を選択
7. **デフォルト有効期間**を日数で設定
8. **作成**をクリック

## テンプレートの使用

証明書の発行またはCSRの署名時に、ドロップダウンからテンプレートを選択します。テンプレートは以下を事前入力します：
- サブジェクトフィールド（上書き可能）
- Key UsageとExtended Key Usage
- 有効期間

## Windows自動登録フラグ

テンプレートには、Windows自動登録プロトコル（XCEP/WSTEP、**設定 → Windows自動登録**で構成）で使用される3つのオプトインフラグがあります：

- **自動登録を許可**: 証明書登録ポリシーでテンプレートを\`autoEnroll=true\`として公開し、GPO/Kerberos認証済みクライアントがユーザー操作なしにログオン時に自動的に要求できるようにします。デフォルトは無効: 実際のADCSと同様、EnrollとAutoenrollは別々の権限であるため、このフラグなしでも手動登録（MMCの「新しい証明書の要求」、\`certreq\`）は可能です。
- **Active Directoryからサブジェクトを構築**: 無人のGPO自動登録向け：クライアントに指定を要求する代わりに、要求元のADオブジェクトから（ADコネクタ経由で）証明書のサブジェクトとSANを導出します。
- **登録をADグループに制限**: 設定されたActive Directoryグループに属するプリンシパル（ネストされたメンバーシップを含む）のみが、Kerberos認証済みエンドポイント経由でこのテンプレートに登録できます。グループ名または完全なDNを入力します。空欄の場合は認証済みプリンシパル全員が許可され、実際のADCSのデフォルトと一致します。リクエストごとの識別情報を持たないユーザー名/パスワードエンドポイントには適用されません。

これらのフラグ付きのテンプレートは、テンプレート一覧に**AD**、**Auto**、**ACL**バッジを表示します。

## 固定サブジェクトフィールド

テンプレートは、WSTEP経由で発行される証明書について、組織サブジェクトフィールド: **C、ST、L、O、OU**: を**固定**できます。固定された値は、クライアントのCSRやActive Directory導出がそのフィールドに何を指定していても、発行されるすべての証明書に強制されます。

- **Common NameとSubject Alternative Nameは影響を受けません**: 要求元ごとに動的なままです
- 動的のままにするにはフィールドを空欄にしてください
- 固定フィールド付きのテンプレートは**Pinned**バッジを表示し、固定値はテンプレート詳細パネルに表示されます

各Windowsクライアントが何を送信するかに関わらず、自動登録されたフリート全体で統一された組織アイデンティティ（例：固定の\`O\`と\`C\`）を保証するために使用します。

## テンプレートの複製

**複製**をクリックして既存のテンプレートのコピーを作成します。元のテンプレートに影響を与えずにコピーを修正できます。

## インポートとエクスポート

### エクスポート
UCMインスタンス間で共有するためにテンプレートをJSONとしてエクスポート。

### インポート
以下からインポート：
- **JSONファイル**: テンプレートJSONファイルをアップロード
- **JSON貼り付け**: テキストエリアにJSONを直接貼り付け

## 一般的なテンプレート例

### TLSサーバー
- Key Usage: Digital Signature、Key Encipherment
- Extended Key Usage: Server Authentication
- 有効期間: 365日

### クライアント認証
- Key Usage: Digital Signature
- Extended Key Usage: Client Authentication
- 有効期間: 365日

### コード署名
- Key Usage: Digital Signature
- Extended Key Usage: Code Signing
- 有効期間: 365日
`
  }
}
