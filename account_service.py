import sqlite3

def get_balance(account_number, owner):
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        cur.execute('''
            SELECT balance FROM accounts where id=? and owner=?''',
            (account_number, owner))
        row = cur.fetchone()
        if row is None:
            return None
        return row[0]
    finally:
        con.close()


def do_transfer(source, target, amount):
    try:
        con = sqlite3.connect('bank.db')
        cur = con.cursor()
        cur.execute('''
            SELECT id FROM accounts where id=?''',
            (target,))
        row = cur.fetchone()
        #If malicious user managed to find an existing user but input wrong password, we don't tell them the password is wrong
        #This has to just show none. These malicious users don't need to know more information than they need
        if row is None:
            return False
        cur.execute('''
            UPDATE accounts SET balance=balance-? where id=?''',
            (amount, source))
        cur.execute('''
            UPDATE accounts SET balance=balance+? where id=?''',
            (amount, target))
        con.commit()
        return True
    finally:
        con.close()