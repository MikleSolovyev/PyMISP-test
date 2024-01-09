from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute


if __name__ == '__main__':
    # Адрес MISP
    misp_url = 'https://192.168.18.129'
    # API ключ пользователя test_api_user@admin.test
    misp_key = "lcXAczQ4S9egkcdEVbgHVzobDvqhsDmuWhuPL3Ts"
    # Отключаем ssl
    misp_verifycert = False
    # Создаем объект подключения к REST API MISP
    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    # Создаем объект события MISP и наполняем его параметрами
    event_obj = MISPEvent()
    event_obj.distribution = 1
    event_obj.threat_level_id = 1
    event_obj.analysis = 1
    event_obj.info = "Test event from host OS"

    # Добавляем событие в MISP
    event = misp.add_event(event_obj)
    # Получаем автоматически сгенерированные id и uuid добавленного события и выводим их
    event_id, event_uuid = event['Event']['id'], event['Event']['uuid']
    print("ID события:", event_id)
    print("UUID события:", event_uuid)
    print()

    # Создаем объект атрибута для события MISP
    attribute = MISPAttribute()
    # Тип атрибута - IP источника
    attribute.type = "ip-src"
    # Значение атрибута - адрес хост системы, с которой запущен скрипт
    attribute.value = "192.168.18.1"
    # Категория атрибута - сетевая активность
    attribute.category = "Network activity"
    # Данное поле атрибута обозначает, что событие не является целью системы обнаружения вторжений
    attribute.to_ids = False

    # Добавляем созданный атрибут к ранее созданному событию по его id и выводим результат
    attribute_to_change = misp.add_attribute(event_id, attribute)
    print("Созданный для события аттрибут:")
    print(attribute_to_change['Attribute']['id'])
    print(attribute_to_change)
    print()

    # Найдем в MISP созданное выше событие по типу аттрибута и его значению
    print("Результат поиска:")
    print(misp.search(controller='attributes', type_attribute='ip-src', value='192.168.18.1'))
