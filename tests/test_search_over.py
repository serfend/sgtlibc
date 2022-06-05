import sgtlibc


def test_more_than_10_libc():
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0xe10)
    result = s.dump()
    is_found, db_description, db_count = s.db_result
    assert db_count > 10, 'this should have more than 10 results'
    assert len(db_description.split('\n')) < 10, 'some result should be hidden'


def test_somany_libc():
    s = sgtlibc.Searcher()
    s.add_condition('puts', 0x0)
    result = s.dump()
    is_found, db_description, db_count = s.db_result
    assert db_count > 1000, 'none condition should return all db'
    assert len(db_description.split('\n')) < 10, 'some result should be hidden'
