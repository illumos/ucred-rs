/*
 * Copyright 2024 Oxide Computer Company
 */

/*
 * We are just using dbg!() to print everything, including some Results, but
 * it does not count as usage from a linting perspective.
 */
#![allow(unused_must_use)]

use ucred::UCred;

fn main() -> std::io::Result<()> {
    let uc = UCred::for_self()?;

    dbg!(uc.euid());
    dbg!(uc.euser());

    dbg!(uc.ruid());
    dbg!(uc.ruser());

    dbg!(uc.suid());
    dbg!(uc.suser());

    dbg!(uc.egid());
    dbg!(uc.egroup());

    dbg!(uc.rgid());
    dbg!(uc.rgroup());

    dbg!(uc.sgid());
    dbg!(uc.sgroup());

    dbg!(uc.groups());

    dbg!(uc.pid());
    dbg!(uc.project());
    dbg!(uc.zoneid());

    dbg!(uc.is_same_zone());
    dbg!(uc.is_global_zone());

    Ok(())
}
