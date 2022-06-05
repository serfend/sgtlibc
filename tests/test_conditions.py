import sgtlibc


def test_condition_count():
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0xaa)
    s.add_condition('puts', 0xaa)
    s.add_condition('puts', 0xaa)
    s.add_condition('puts', 0xaa)
    c = s.list_conditions()
    assert len(list(c)) == 1

def test_condition_count_multi():
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0xaa)
    s.add_condition('puts2', 0xaa)
    s.add_condition('puts3', 0xaa)
    s.add_condition('puts4', 0xaa)
    c = s.list_conditions()
    assert len(list(c)) == 4
