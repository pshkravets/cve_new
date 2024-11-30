import requests

from datetime import datetime, timedelta

from fastapi import FastAPI, APIRouter, status, HTTPException
from fastapi.responses import JSONResponse

from database import es_client

app = FastAPI(debug=True)

router = APIRouter()


@router.post('/init-db/')
def init_db():
    response = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    es_client.indices.create(index='cve', ignore=400)
    es_client.index(index='cve', id=1, document=response.json())



@router.get('/get/all/')
def get_all():
    response = es_client.get(index='cve', id=1)
    five_days = datetime.now() - timedelta(days=5)
    sorted_response = []
    for vuln in response['_source']['vulnerabilities']:
        if datetime.strptime(vuln['dateAdded'], '%Y-%m-%d') >= five_days:
            sorted_response.append(vuln)
    if len(sorted_response) > 40:
        sorted_response = sorted_response[:40]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={'cves': sorted_response}
    )


@router.get('/get/new/')
def get_new():
    response = es_client.get(index='cve', id=1)
    sorted_response = sorted(response['_source']['vulnerabilities'], key=lambda x: x['dateAdded'])
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={'cves': sorted_response[-10:]}
    )


@router.get('/get/known')
def get_known():
    response = es_client.get(index='cve', id=1)
    filtered_response = []
    for vuln in response['_source']['vulnerabilities']:
        if vuln['knownRansomwareCampaignUse'] == 'Known':
            filtered_response.append(vuln)

    if len(filtered_response) > 10:
        filtered_response = filtered_response[:10]
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={'cves': filtered_response}
    )


@router.get('/get/')
def get_keyword(query: str):
    response = es_client.get(index='cve', id=1)
    filtered_response = []
    for vuln in response['_source']['vulnerabilities']:
        if any(query.lower() in str(value).lower() for value in vuln.values()):
            filtered_response.append(vuln)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={'cves': filtered_response}
    )


@router.get('/info/')
def info():
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            '/get/all/': 'Вертає 40',
            '/get/new/': 'Скоріш за все нічого не виведе, потрібно вказати замість 5ти хоча б 10 в залежності від того'
                         'коли перевіряєте завдання timedelta(days=5) ',

            '/get/known': 'Просто шукає словники в яких значення ключа knownRansomwareCampaignUse = Known',
            '/get': 'Шукає по ключовому слові',
            'author': 'Кравець Павло (pashkevuchpasha@gmail.com)'
        }
    )



app.include_router(router)


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)