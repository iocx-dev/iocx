import pytest
from iocx.extractors.urls.bare_domain import extract_bare_domains


def test_bare_domain_basic():
    text = "Contact us at example.com"
    assert extract_bare_domains(text) == ["example.com"]


def test_bare_domain_subdomain():
    text = "Try sub.domain.co.uk"
    assert extract_bare_domains(text) == ["sub.domain.co.uk"]


def test_bare_domain_no_false_positives():
    text = "Weird string: d.dp."
    assert extract_bare_domains(text) == []
