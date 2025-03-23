
/// Resource struct holds anything you find relevant that you need
/// on a per packet basis.
pub trait Resource: Clone + Send + Sync {
    fn new() -> Self;
}