INSERT INTO
    users (id, email)
VALUES
    (
        'f7b3b1b4-3b3b-4b3b-8b3b-3b3b3b3b3b3b',
        'testgmail@gmail.com'
    ) ON CONFLICT DO NOTHING;

INSERT INTO
    users (id, email)
VALUES
    (
        'c7190d84-76f7-4088-a2fa-10c55cb0bf68',
        'testmail@mail.ru'
    ) ON CONFLICT DO NOTHING;

INSERT INTO
    users (id, email)
VALUES
    (
        '3e60628a-7c9c-464f-97fe-e409727cdfba',
        'testyandex@yandex.ru'
    ) ON CONFLICT DO NOTHING;
