# clippy-tracing

A tool to add, remove and check for `log_instrument::instrument` in large
projects where it is infeasible to manually add it to thousands of functions.

## Usage

This is tested in the
[`readme()` integration test](../clippy-tracing/tests/integration_tests.rs) .

```rust
fn main() {
    println!("Hello World!");
}
fn add(lhs: i32, rhs: i32) -> i32 {
    lhs + rhs
}
#[cfg(tests)]
mod tests {
    fn sub(lhs: i32, rhs: i32) -> i32 {
        lhs - rhs
    }
    #[test]
    fn test_one() {
        assert_eq!(add(1,1), sub(2, 1));
    }
}
```

```bash
clippy-tracing --action check # Missing instrumentation at {path}:9:4.\n
echo $? # 2
clippy-tracing --action fix
echo $? # 0
```

```rust
#[log_instrument::instrument(level = "trace", skip())]
fn main() {
    println!("Hello World!");
}
#[log_instrument::instrument(level = "trace", skip(lhs, rhs))]
fn add(lhs: i32, rhs: i32) -> i32 {
    lhs + rhs
}
#[cfg(tests)]
mod tests {
    #[log_instrument::instrument(level = "trace", skip(lhs, rhs))]
    fn sub(lhs: i32, rhs: i32) -> i32 {
        lhs - rhs
    }
    #[test]
    fn test_one() {
        assert_eq!(add(1,1), sub(2, 1));
    }
}
```

```bash
clippy-tracing --action check
echo $? # 0
clippy-tracing --action strip
echo $? # 0
```

```rust
fn main() {
    println!("Hello World!");
}
fn add(lhs: i32, rhs: i32) -> i32 {
    lhs + rhs
}
#[cfg(tests)]
mod tests {
    fn sub(lhs: i32, rhs: i32) -> i32 {
        lhs - rhs
    }
    #[test]
    fn test_one() {
        assert_eq!(add(1,1), sub(2, 1));
    }
}
```
