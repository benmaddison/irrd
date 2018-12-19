# flake8: noqa: W291, W293
from itertools import cycle, repeat

import pytest
import textwrap
from unittest.mock import Mock

from irrd.storage.models import DatabaseOperation
from ..nrtm_generator import NRTMGenerator, NRTMGeneratorException


@pytest.fixture()
def prepare_generator(monkeypatch):
    mock_dh = Mock()
    mock_djq = Mock()
    mock_dsq = Mock()

    monkeypatch.setattr('irrd.mirroring.nrtm_generator.RPSLDatabaseJournalQuery', lambda: mock_djq)
    monkeypatch.setattr('irrd.mirroring.nrtm_generator.DatabaseStatusQuery', lambda: mock_dsq)

    responses = cycle([
        repeat({'serial_oldest_journal': 100, 'serial_newest_journal': 200}),
        [
            {
                'object_text': 'object 1 🦄\n',
                'operation': DatabaseOperation.add_or_update,
                'serial_nrtm': 120,
            },
            {
                'object_text': 'object 2 🌈\n',
                'operation': DatabaseOperation.delete,
                'serial_nrtm': 180,
            },
        ],
    ])
    mock_dh.execute_query = lambda q: next(responses)

    yield NRTMGenerator(), mock_dh


class TestNRTMGenerator:
    def test_generate_serial_range_v3(self, prepare_generator):
        generator, mock_dh = prepare_generator
        result = generator.generate('TEST', '3', 110, 190, mock_dh)

        assert result == textwrap.dedent("""
        %START Version: 3 TEST 110-190

        ADD 120
        
        object 1 🦄
        
        DEL 180
        
        object 2 🌈
        
        %END TEST""").strip()

    def test_generate_serial_range_v1(self, prepare_generator):
        generator, mock_dh = prepare_generator
        result = generator.generate('TEST', '1', 110, 190, mock_dh)

        assert result == textwrap.dedent("""
        %START Version: 1 TEST 110-190

        ADD

        object 1 🦄

        DEL

        object 2 🌈

        %END TEST""").strip()

    def test_generate_until_last(self, prepare_generator):
        generator, mock_dh = prepare_generator
        result = generator.generate('TEST', '3', 110, None, mock_dh)

        assert result == textwrap.dedent("""
        %START Version: 3 TEST 110-200

        ADD 120

        object 1 🦄

        DEL 180

        object 2 🌈

        %END TEST""").strip()

    def test_serial_range_start_higher_than_low(self, prepare_generator):
        generator, mock_dh = prepare_generator

        with pytest.raises(NRTMGeneratorException) as nge:
            generator.generate('TEST', '3', 200, 190, mock_dh)
        assert 'Start of the serial range (200) must be lower or equal to end of the serial range (190)' in str(nge)

    def test_serial_start_too_low(self, prepare_generator):
        generator, mock_dh = prepare_generator

        with pytest.raises(NRTMGeneratorException) as nge:
            generator.generate('TEST', '3', 10, 190, mock_dh)
        assert 'Serials 10 - 100 do not exist' in str(nge)

    def test_serial_start_too_high(self, prepare_generator):
        generator, mock_dh = prepare_generator

        with pytest.raises(NRTMGeneratorException) as nge:
            generator.generate('TEST', '3', 202, None, mock_dh)
        assert 'Serials 200 - 202 do not exist' in str(nge)

    def test_serial_end_too_high(self, prepare_generator):
        generator, mock_dh = prepare_generator

        with pytest.raises(NRTMGeneratorException) as nge:
            generator.generate('TEST', '3', 110, 300, mock_dh)
        assert 'Serials 200 - 300 do not exist' in str(nge)

    def test_no_new_updates(self, prepare_generator):
        # This message is only triggered when starting from a serial
        # that is the current plus one, until LAST
        generator, mock_dh = prepare_generator

        result = generator.generate('TEST', '3', 201, None, mock_dh)
        assert result == '% Warning: there are no newer updates available'
