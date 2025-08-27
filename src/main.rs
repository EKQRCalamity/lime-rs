mod patterns {
    mod offsets;
}

mod devmem {
    mod write;
    mod read;
}

mod procvm {
    mod read;
    mod write;
}

mod procmem {
    mod read;
    mod write;
    mod procmem;
}

mod ptrace {
    mod read;
    mod write;
}

pub mod traits;
pub mod errors;

fn main() {
    println!("Hello, world!");
}
