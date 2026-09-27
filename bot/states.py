"""FSM holatlari."""
from aiogram.fsm.state import State, StatesGroup


class AddProduct(StatesGroup):
    title = State()
    description = State()
    price = State()
    kind = State()
    payload = State()


class AddEngagement(StatesGroup):
    domain = State()
    note = State()


class AddOperator(StatesGroup):
    tg_id = State()


class AddPlan(StatesGroup):
    title = State()
    description = State()
    price = State()
    chat_id = State()


class ScanFlow(StatesGroup):
    passive_domain = State()
    active_domain = State()
    deep_domain = State()


class VerifyFlow(StatesGroup):
    domain = State()
