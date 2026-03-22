# ruleid: SEC-005
# Arbitrary code execution via exec()
user_code = "print('hello')"
exec(user_code)
