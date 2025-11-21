from ioc_ranger.validators import classify


def test_classify_hash():
    assert classify("44d88612fea8a8f36de82e1278abb02f") == "hash"
    assert classify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"


def test_classify_ip():
    assert classify("8.8.8.8") == "ip"
    assert classify("127.0.0.1") == "ip"


def test_classify_domain():
    assert classify("example.com") == "domain"
    assert classify("google.co.uk") == "domain"


def test_classify_url():
    assert classify("http://example.com") == "url"
    assert classify("https://google.com/search?q=test") == "url"
