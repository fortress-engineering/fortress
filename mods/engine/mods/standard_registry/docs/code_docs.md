# Standard Registry Code

`identity.rs` validates stable entity and rule IDs. `standard.rs` exposes the
draft registry and loads one exact standard manifest plus its complete declared
rule-document set, rejecting missing, extra, duplicate, or invalid records.
