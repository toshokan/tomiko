#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Display {
    Page,
    Popup,
    Touch,
    Wap
}

#[derive(Debug)]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount
}

