from dataclasses import dataclass
from enum import Enum
from os import getenv
from threading import Lock


class State(Enum):
    GREETING = 0
    AUTHORIZATION = 1
    TRANSACTION = 2
    UPDATE = 3
    GOODBYE = 4


@dataclass
class Message:
    message_id: int
    content: str
    deleted: bool = False


@dataclass
class Maildrop:
    name: str
    messages: dict[int, Message]
    lock: Lock


@dataclass
class Session:
    username: str | None = None
    maildrop: Maildrop | None = None


# 110 is the RFC compliant port, but it's handy to test locally on a non-privileged port number >1024
PORT = 110
COMMAND_END = "\r\n"
MAX_RESPONSE_LEN = 512
SEPARATOR = " "
MAX_ARG_LEN = 40
POSITIVE_INDICATOR = "+OK"
NEGATIVE_INDICATOR = "-ERR"
MULTILINE_END = ".\r\n"
TERMINATION_OCTET = "."
# A real POP3 server would use a stateful database.
# For simplicity, we always start with the same static mailbox
MY_MAILDROP = list(enumerate(["hello", "world" * 128]))
SECRET_MAIL_DROP = list(enumerate(["some secrets"]))
from threading import Lock

MAILBOX = {
    "JCRAWFORD": Maildrop(
        "JCRAWFORD",
        {i: Message(i, content) for i, content in MY_MAILDROP},
        Lock(),
    ),
    "ADMIN": Maildrop(
        "ADMIN",
        {i: Message(i, content) for i, content in SECRET_MAIL_DROP},
        Lock(),
    ),
}

AUTH = {
    "JCRAWFORD": "NOT_A_REAL_PASSWORD",
    "ADMIN": "NOT_ADMIN_FOR_ONCE",
}


class Command:
    COMMAND_TYPES = {
        # command name -> (args, allowed_states)
        "QUIT": ([0], {State.AUTHORIZATION, State.TRANSACTION}),
        "USER": ([1], {State.AUTHORIZATION}),
        "PASS": ([1], {State.AUTHORIZATION}),
        "STAT": ([0], {State.TRANSACTION}),
        "LIST": ([0, 1], {State.TRANSACTION}),
        "RETR": ([1], {State.TRANSACTION}),
        "DELE": ([1], {State.TRANSACTION}),
        "NOOP": ([0], {State.TRANSACTION}),
        "RSET": ([0], {State.TRANSACTION}),
    }

    def __init__(self, raw: str):
        tokens = raw.upper().rstrip(COMMAND_END).split(SEPARATOR)
        self.command, self.args = tokens[0], tokens[1:]

    def _no_such_message(self, session: Session) -> bool:
        return (
            not self.args[0].isdigit()
            or int(self.args[0]) not in session.maildrop.messages
            or session.maildrop.messages[int(self.args[0])].deleted
        )

    def _invalid_command_response(
        self, state: State, session: Session, mailbox: dict[str, Maildrop]
    ) -> str | None:
        if any([len(arg) > MAX_ARG_LEN for arg in self.args]):
            return f"{NEGATIVE_INDICATOR} command arg length exceeeded {MAX_ARG_LEN} octets{COMMAND_END}"
        if self.command not in self.COMMAND_TYPES:
            return f"{NEGATIVE_INDICATOR} unknown command{COMMAND_END}"
        if session.maildrop is None and state in {
            State.TRANSACTION,
            State.UPDATE,
        }:
            return f"{NEGATIVE_INDICATOR} Cannot act without maildrop{COMMAND_END}"
        args, allowed_states = self.COMMAND_TYPES[self.command]
        if len(self.args) not in args:
            return f"{NEGATIVE_INDICATOR} command requires {args} arguments{COMMAND_END}"
        if state not in allowed_states:
            return (
                f"{NEGATIVE_INDICATOR} invalid command in {state}{COMMAND_END}"
            )

    def _handle_list(self, state: State, session: Session) -> str:
        if self.args:
            if self._no_such_message(session):
                return f"{NEGATIVE_INDICATOR} no such message{COMMAND_END}"
            else:
                return f"{POSITIVE_INDICATOR} {self.args[0]} {len(session.maildrop.messages[int(self.args[0])].content)}{COMMAND_END}"
        else:
            undeleted_messages = [
                (message_id, m)
                for message_id, m in session.maildrop.messages.items()
                if not m.deleted
            ]
            header = f"{POSITIVE_INDICATOR} {len(undeleted_messages)} {sum([len(msg.content) for msg_id, msg in undeleted_messages])}{COMMAND_END}"
            body = "".join(
                [
                    f"{msg_id} {len(msg.content)}{COMMAND_END}"
                    for msg_id, msg in undeleted_messages
                ]
            )
            return header + body + MULTILINE_END

    def _handle_retr(self, state: State, session: Session) -> str:
        if self._no_such_message(session):
            return f"{NEGATIVE_INDICATOR} no such message{COMMAND_END}"
        else:
            header = f"{POSITIVE_INDICATOR} message follows{COMMAND_END}"
            content = session.maildrop.messages[int(self.args[0])].content
            body = ""
            while content:
                body += f"{content[:MAX_RESPONSE_LEN-len(COMMAND_END)]}{COMMAND_END}"
                content = content[MAX_RESPONSE_LEN - len(COMMAND_END) :]
            return header + body + MULTILINE_END

    def _handle_pass(
        self, state: State, session: Session, mailbox: dict[str, Maildrop]
    ):
        if session.username is None:
            return f"{NEGATIVE_INDICATOR} PASS must come after successful USER{COMMAND_END}"
        password = " ".join(self.args)  # to allow for spaces in password
        if password != AUTH[session.username]:
            session.username = None
            return f"{NEGATIVE_INDICATOR} invalid password{COMMAND_END}"
        if not mailbox[session.username].lock.acquire(False):
            session.username = None
            return f"{NEGATIVE_INDICATOR} maildrop already locked{COMMAND_END}"
        session.maildrop = mailbox[session.username]
        messages = session.maildrop.messages.items()
        return f"{POSITIVE_INDICATOR} {session.username}'s maildrop has {len(messages)} messages ({sum([len(msg.content) for msg_id, msg in messages])} octets){COMMAND_END}"

    def respond(
        self,
        state: State,
        session: Session,
        mailbox: dict[str, Maildrop] = MAILBOX,
    ) -> str:
        invalid_command_response = self._invalid_command_response(
            state, session, mailbox
        )
        if invalid_command_response is not None:
            return invalid_command_response
        if self.command == "USER":
            if self.args[0] not in mailbox:
                return f"{NEGATIVE_INDICATOR} sorry, no mailbox for {self.args[0]} here{COMMAND_END}"
            session.username = self.args[0]
            return f"{POSITIVE_INDICATOR} {self.args[0]} is a valid mailbox{COMMAND_END}"
        if self.command == "PASS":
            return self._handle_pass(state, session, mailbox)
        if self.command == "STAT":
            return f"{POSITIVE_INDICATOR} {len(session.maildrop.messages)} {sum([len(msg.content) for msg in session.maildrop.messages.values()])}{COMMAND_END}"
        if self.command == "LIST":
            return self._handle_list(state, session)
        if self.command == "RETR":
            return self._handle_retr(state, session)
        if self.command == "DELE":
            if self._no_such_message(session):
                return f"{NEGATIVE_INDICATOR} no such message{COMMAND_END}"
            else:
                session.maildrop.messages[int(self.args[0])].deleted = True
                return f"{POSITIVE_INDICATOR} message {self.args[0]} deleted{COMMAND_END}"
        if self.command == "NOOP":
            return f"{POSITIVE_INDICATOR}{COMMAND_END}"
        if self.command == "RSET":
            for message in session.maildrop.messages.values():
                message.deleted = False
            return f"{POSITIVE_INDICATOR} maildrop has {len(session.maildrop.messages)} messages ({sum([len(msg.content) for msg_id, msg in session.maildrop.messages.items()])} octets){COMMAND_END}"
        if self.command == "QUIT":
            username = session.username
            if state == State.TRANSACTION:
                session.maildrop.messages = {
                    msg_id: msg
                    for msg_id, msg in session.maildrop.messages.items()
                    if not msg.deleted
                }
                session.maildrop.lock.release()
            session.username = None
            session.maildrop = None
            return f"{POSITIVE_INDICATOR} {username} POP3 server signing off{COMMAND_END}"
