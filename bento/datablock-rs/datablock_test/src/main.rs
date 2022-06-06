extern crate datablock;
use datablock::DataBlock;

fn print_buf(buf: &[u8]) {
    for i in 0..buf.len() {
        print!("{:02x} ", buf[i]);
    }
    println!("");
}

#[derive(DataBlock)]
struct Foo<T> where {
    a : u32,
    b : T,
}

fn main() {
    let mut buf : [u8; 50] = [0; 50];

    let mut obj : [u32; 5] = [1, 2, 3, 4, 50];
    println!("{} {}", obj.len(), std::mem::size_of_val(&obj));

    let mut x = Foo::<u32> { a : 0xdead, b : obj[3]};
    x.b = 0xabcd;

    let _r = obj.extract_from(&buf);
    let _r = obj.dump_into(&mut buf);
    let r = x.dump_into(&mut buf);
    println!("{} {}", std::mem::size_of_val(&x), r.unwrap_or(999999));
    print_buf(&buf);

    let mut y : Foo::<u32> = Foo {a: 0, b: 0};
    let _r = y.extract_from(&buf);

    for i in 0..obj.len() {
        print!("{} ", obj[i]);
    }

    println!("{:x} {:x} {:x}", y.a, y.b, y.b);
    println!("done");
}
