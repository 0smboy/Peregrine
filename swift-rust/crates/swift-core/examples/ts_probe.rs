fn main() {
    let t: Result<swift_core::Timestamp, _> = "0".parse();
    println!("parse '0': {:?}", t.map(|x| x.internal()));
    let t: Result<swift_core::Timestamp, _> = "1751500001.00000_0000000000000001".parse();
    println!("parse offset: {:?}", t.map(|x| x.internal()));
}
