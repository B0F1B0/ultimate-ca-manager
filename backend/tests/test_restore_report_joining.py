"""The two warnings an archive carries read as sentences, whatever precedes.

There are two ways to ask for a restore and each writes its own message, so
the joining lives in one place. It has to survive punctuation neither caller
writes today, because the next caller is the one that will.
"""
import pytest

from services.backup.restore_report import with_restore_warnings


ONE = {'key_mismatches': ['issuing-ca']}
TWO = {'key_mismatches': ['issuing-ca', 'ocsp-responder']}
SECTIONS = {'sections_not_restored': ['hsm_providers']}


class TestNothingToWarnAbout:
    @pytest.mark.parametrize("message,expected", [
        ('Restore completed.', 'Restore completed.'),
        ('Restore completed', 'Restore completed.'),
        # `rstrip('.')` ate every trailing stop, so an ellipsis became a dot.
        ('Restoring...', 'Restoring...'),
        # And a full stop was added regardless, giving `Did it work?.`
        ('Did it work?', 'Did it work?'),
        ('Done!', 'Done!'),
        ('', ''),
    ])
    def test_the_message_comes_back_punctuated_as_it_was(
            self, message, expected):
        assert with_restore_warnings(message, {}) == expected


class TestTheClausesReadAsSentences:
    def test_a_message_ending_in_a_question_is_not_given_a_full_stop(self):
        answer = with_restore_warnings('Did it work?', ONE)
        assert answer.startswith('Did it work? '), answer
        assert '?.' not in answer, answer

    def test_a_message_ending_in_a_full_stop_gains_exactly_one(self):
        answer = with_restore_warnings('Restore completed.', ONE)
        assert '..' not in answer, answer
        assert answer.startswith('Restore completed. '), answer

    def test_a_message_without_punctuation_gains_one(self):
        answer = with_restore_warnings('Restore completed', ONE)
        assert answer.startswith('Restore completed. '), answer

    def test_an_empty_message_does_not_start_with_a_full_stop(self):
        answer = with_restore_warnings('', ONE)
        assert not answer.startswith('.'), answer
        assert answer.endswith('.'), answer

    def test_both_clauses_are_separated(self):
        answer = with_restore_warnings(
            'Restore completed.', {**SECTIONS, **TWO})
        assert '..' not in answer, answer
        assert 'hsm_providers' in answer and 'ocsp-responder' in answer


class TestTheCountIsSaidCorrectly:
    def test_one_record_is_singular(self):
        answer = with_restore_warnings('Restore completed.', ONE)
        assert '1 record carries' in answer, answer

    def test_several_records_are_plural(self):
        answer = with_restore_warnings('Restore completed.', TWO)
        assert '2 records carry' in answer, answer

    def test_a_truncated_list_says_how_many_it_left_out(self):
        many = {'key_mismatches': [f'ca-{n}' for n in range(8)]}
        answer = with_restore_warnings('Restore completed.', many)
        assert '8 records carry' in answer, answer
        assert 'and 3 more' in answer, (
            f'five are listed and three are dropped in silence: {answer}')
