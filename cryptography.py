from passlib.context import CryptContext

cryptography = CryptContext(schemes=['bcrypt'], deprecated='auto')
