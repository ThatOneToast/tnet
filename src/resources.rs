
pub trait Resource: Clone + Send + Sync {
    fn new() -> Self;
}