pub(crate) mod append_handle;
pub(crate) mod create_account;
pub mod domain;
pub mod factory;
pub(crate) mod inputs;
pub(crate) mod migrate;
pub(crate) mod prepare;

pub use domain::{TandemAction, Theme};
pub use factory::{get_action, SUPPORTED_ACTIONS};

pub(crate) use append_handle::ActionAppendHandle;
pub(crate) use create_account::ActionCreateAccount;
pub(crate) use inputs::{get_did_plc_input, get_handle_input, get_jwk_input};
pub(crate) use migrate::ActionMigrate;
pub(crate) use prepare::ActionPrepare;
