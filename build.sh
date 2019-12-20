rm dist.zip
ORIGIN=`pwd`
cp -rc ./src ./tmp
docker run --rm -v "$PWD/tmp":/var/task lambci/lambda:build-python3.6 pip install -r requirements.txt -t .
cd tmp
zip -r dist *
cd $ORIGIN
mv ./tmp/dist.zip ./dist.zip
rm -rf tmp
