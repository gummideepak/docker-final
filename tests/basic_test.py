"""This test the homepage"""

def test_home_page(client):
    """This makes the index page"""
    response = client.get("/")
    assert response.status_code == 200