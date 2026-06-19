from vaultblob.cli import parse_byte_size


def test_parse_human_byte_sizes() -> None:
    assert parse_byte_size("4096") == 4096
    assert parse_byte_size("5kb") == 5 * 1024
    assert parse_byte_size("10MB") == 10 * 1024 * 1024
    assert parse_byte_size("1 gb") == 1024**3
    assert parse_byte_size("512k") == 512 * 1024
