pub fn join(container: impl IntoIterator<Item = impl ToString>, sep: &str) -> String {
    container
        .into_iter()
        .map(|item| item.to_string())
        .collect::<Vec<_>>()
        .join(sep)
}

pub fn comma_join(container: impl IntoIterator<Item = impl ToString>) -> String {
    join(container, ", ")
}
