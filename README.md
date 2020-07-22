# checkssl

> Check SSL certificate

## Example
```rust
use checkssl::CheckSSL;

let certificate = CheckSSL::from_domain("rust-lang.org").unwrap();
println!("{:?}", certificate)

```

## License
MIT @Aldi Priya Perdana