from fastapi.testclient import TestClient
from app.main import app  # включаем сюда ваш инстанс FastAPI приложения с названием "app"

# создаём инстанс TestClient для тестирования FastAPI приложения
client = TestClient(app)


def test_calculate_sum():
    # Test case 1: валидные входные данные
    response = client.get("/sum/?a=5&b=10")
    assert response.status_code == 200
    assert response.json() == {"result": 15}

    # Test case 2: отрицательные числа
    response = client.get("/sum/?a=-8&b=-3")
    assert response.status_code == 200
    assert response.json() == {"result": -11}

    # Test case 3: ноль и положительное число
    response = client.get("/sum/?a=0&b=7")
    assert response.status_code == 200
    assert response.json() == {"result": 7}

    # Test case 4: одно число не введено
    response = client.get("/sum/?a=3")
    assert response.status_code == 422  # Unprocessable Entity (validation error)
    assert response.json() == {
        "detail": [
            {
                "loc": ["query", "b"],
                "msg": "field required",
                "type": "value_error.missing"
            }
        ]
    }
