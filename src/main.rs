mod internal {
    pub mod patterns {
        pub mod offsets;
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
    pub mod scan;
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
