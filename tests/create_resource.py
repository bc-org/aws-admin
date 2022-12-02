from admin import admin


def test_create_resources():
    creator_tag = 'tejas'
    resource_prefix = 'doors'
    alert_email = 'tejas.morbagalharish@brockmann-consult.de'
    bucket_size_limit = 12345
    creator = admin.AwsResourceCreator(
        aws_account_number='346516713328',
        creator_tag=creator_tag,
        resource_prefix=resource_prefix,
        alert_email=alert_email,
        bucket_size_limit_bytes=bucket_size_limit,
        project='doors'
    )
    creator.create_resources()
