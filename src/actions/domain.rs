use anyhow::Result;
use async_trait::async_trait;
use dialoguer::{console::Style, theme::ColorfulTheme};

pub struct Theme<'a> {
    pub red_bold: Style,
    pub yellow_bold: Style,
    pub green: Style,
    pub white_dim: Style,
    pub colorful_theme: &'a ColorfulTheme,
}

#[async_trait]
pub trait TandemAction: Sync + Send {
    async fn run(&self) -> Result<()>;
}
