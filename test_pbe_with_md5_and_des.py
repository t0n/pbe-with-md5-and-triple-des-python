from pbe_with_md5_and_triple_des import PBEWithMD5AndDES, PBEWithMD5AndTripleDES


def test_pbe_with_md5_and_des():
    password = 'secret'
    plain_text = 'Hello World!'
    cipher = PBEWithMD5AndDES()
    encrypted_text = cipher.encrypt(plain_text, password)
    decrypted_text = cipher.decrypt(encrypted_text, password)
    assert plain_text == decrypted_text


def test_pbe_with_md5_and_triple_des():
    password = 'secret'
    plain_text = 'Hello World!'
    cipher = PBEWithMD5AndTripleDES()
    encrypted_text = cipher.encrypt(plain_text, password)
    decrypted_text = cipher.decrypt(encrypted_text, password)
    assert plain_text == decrypted_text


def test_pbe_with_md5_and_triple_des_decryption():
    """
    Some prepared examples, encoded using Jasypt lib for Java.
    """
    test_data = [
        ('hello',               'NiwUbfH5mSK9HhsgntENfA==',             'abcd1234'),
        ('hello',               'AGxuQtY9J/XUoGqUrUlCNQ==',             'abcd1234'),
        ('hello',               'LYgMLQSth4/iaNvLwYfvdQ==',             'abcd1234'),

        ('hello',               'YSJ3IhOw6xGOGR82vCMggg==',             'mnopqrst'),
        ('hello',               'hOG75IYw+KR5G/oKRPZReQ==',             'mnopqrst'),
        ('hello',               'BYi598iZOU8QITOWkmbmDg==',             'mnopqrst'),
    ]
    cipher = PBEWithMD5AndTripleDES()
    for td in test_data:
        decrypted_text = cipher.decrypt(td[1], td[2])
        assert td[0] == decrypted_text
