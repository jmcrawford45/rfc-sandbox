import pytest

from rfc_1939.core import *

VALID_MESSAGES = {
    1: Message(1, "hello, world"),
    2: Message(2, "world"),
    3: Message(3, "deleted", True),
}
VALID_SESSION = Session(
    "JCRAWFORD", Maildrop("JCRAWFORD", VALID_MESSAGES, Lock())
)


@pytest.mark.parametrize(
    "command,state,session,contains",
    [
        ("UNKNOWN", State.GREETING, Session(), "unknown command"),
        (f"USER {'long' * 15}", State.AUTHORIZATION, Session(), "arg length"),
        (
            "USER not_found",
            State.AUTHORIZATION,
            Session(),
            "no mailbox for not_found",
        ),
        ("STAT", State.TRANSACTION, Session(), "without maildrop"),
        ("STAT", State.UPDATE, Session(), "without maildrop"),
        (
            "PASS NOT_A_PASSWORD",
            State.GREETING,
            Session(),
            f"invalid command in {State.GREETING}",
        ),
        (
            "PASS NOT_A_PASSWORD",
            State.AUTHORIZATION,
            Session(),
            "must come after successful USER",
        ),
        (
            "PASS INVALID_PASSWORD",
            State.AUTHORIZATION,
            Session("JCRAWFORD"),
            "invalid password",
        ),
        ("LIST 5", State.TRANSACTION, VALID_SESSION, "no such message"),
        ("LIST 3", State.TRANSACTION, VALID_SESSION, "no such message"),
        ("RETR 5", State.TRANSACTION, VALID_SESSION, "no such message"),
        ("RETR 3", State.TRANSACTION, VALID_SESSION, "no such message"),
        ("DELE 5", State.TRANSACTION, VALID_SESSION, "no such message"),
        ("DELE 3", State.TRANSACTION, VALID_SESSION, "no such message"),
    ],
)
def test_invalid_command(
    command: str, state: State, session: Session, contains: str
):
    response = Command(command).respond(state, session)
    assert response.endswith(COMMAND_END)
    assert response.startswith(NEGATIVE_INDICATOR)
    assert contains.upper() in response.upper()


def test_invalid_pass_already_locked():
    lock = Lock()
    mail = Maildrop("JCRAWFORD", list(), lock)
    mail.lock.acquire()
    session = Session("JCRAWFORD", {"JCRAWFORD": mail})
    response = Command(f"PASS {AUTH['JCRAWFORD']}").respond(
        State.AUTHORIZATION, session, {"JCRAWFORD": mail}
    )
    contains = "already locked"
    assert response.endswith(COMMAND_END)
    assert response.startswith(NEGATIVE_INDICATOR)
    assert contains.upper() in response.upper()


def _assert_valid_single_line_command(
    command: str, state: State, session: Session, mailbox: dict[str, Maildrop]
) -> str:
    response = Command(command).respond(state, session, mailbox)
    assert response.startswith(POSITIVE_INDICATOR)
    assert response.endswith(COMMAND_END)
    return response


def test_valid_integration():
    lock = Lock()
    messages = {
        1: Message(1, "hello, world"),
        2: Message(2, "world"),
        3: Message(3, "long message" * 100),
    }
    mail = Maildrop("JCRAWFORD", messages, lock)
    mailbox = {"JCRAWFORD": mail}
    session = Session()
    state = State.AUTHORIZATION
    _assert_valid_single_line_command(
        "USER jcrawford", state, session, mailbox
    )
    assert session.username == "JCRAWFORD"
    _assert_valid_single_line_command(
        f"PASS {AUTH['JCRAWFORD']}", state, session, mailbox
    )
    assert lock.locked()
    state = State.TRANSACTION
    _assert_valid_single_line_command("NOOP", state, session, mailbox)
    response = _assert_valid_single_line_command(
        "STAT", state, session, mailbox
    )
    assert f"3 {sum([len(m.content) for m in messages.values()])}" in response
    response = _assert_valid_single_line_command(
        "LIST 2", state, session, mailbox
    )
    assert f'2 {len("world")}' in response
    response = _assert_valid_single_line_command(
        "LIST", state, session, mailbox
    )
    assert f'2 {len("world")}' in response
    assert f'1 {len("hello, world")}' in response
    assert response.endswith(MULTILINE_END)
    response = _assert_valid_single_line_command(
        "RETR 1", state, session, mailbox
    )
    assert response.split(COMMAND_END) == [
        f"{POSITIVE_INDICATOR} message follows",
        "hello, world",
        TERMINATION_OCTET,
        "",
    ]
    assert response.endswith(MULTILINE_END)
    response = _assert_valid_single_line_command(
        "RETR 3", state, session, mailbox
    )
    assert "long message" in response
    assert all(
        [len(line) <= MAX_RESPONSE_LEN for line in response.split(COMMAND_END)]
    )
    assert response.endswith(MULTILINE_END)
    response = _assert_valid_single_line_command(
        "DELE 1", state, session, mailbox
    )
    assert "message 1 deleted" in response
    assert messages[1].deleted
    response = _assert_valid_single_line_command(
        "RSET", state, session, mailbox
    )
    assert not messages[1].deleted
    assert "3 messages" in response
    response = _assert_valid_single_line_command(
        "DELE 1", state, session, mailbox
    )
    assert "message 1 deleted" in response
    assert messages[1].deleted
    _assert_valid_single_line_command("QUIT", state, session, mailbox)
    assert not lock.locked()
    assert session.username is None
    assert session.maildrop is None
