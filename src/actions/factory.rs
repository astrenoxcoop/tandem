use super::{ActionAppendHandle, ActionPrepare, TandemAction, Theme};
use anyhow::{anyhow, Result};

pub fn get_action<'a>(
    selected_operation: usize,
    theme: &'a Theme<'a>,
    http_client: &reqwest::Client,
    plc: &str,
) -> Result<Box<dyn TandemAction + 'a>> {
    match selected_operation {
        0 => Ok(Box::new(ActionPrepare::new(theme, http_client, plc)) as Box<dyn TandemAction>),
        1 => {
            Ok(Box::new(ActionAppendHandle::new(theme, http_client, plc)) as Box<dyn TandemAction>)
        }
        _ => Err(anyhow!("Unsupported operation")),
    }
}
