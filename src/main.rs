mod internal {
    mod patterns {
        mod offsets;
    }
}

mod devmem {
    mod write;
    mod read;
}

mod procvm {
    mod read;
    mod write;
}

pub mod procmem {
    pub mod read;
    pub mod write;
    pub mod procmem;
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
