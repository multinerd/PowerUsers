#Replacing the contents like namespaces in the files:

```
#find . -name "*.*" -print0 | xargs -0 sed -i '' -e 's/PDMLab\.AwesomeProject\.WithAnUglyTypo/PDMLab.AwesomeProject.WithoutAnUglyTypo/g'
find . -name "*.*" -print0 | xargs -0 sed -i '' -e 's/MyCompanyName\.AbpZeroTemplate/WesternBeef/g'
```


Renaming files and folders:

```
#for i in $(find * -maxdepth 1); do mv $i $(echo $i | sed 's/PDMLab\.AwesomeProject\.WithAnUglyTypo/PDMLab.AwesomeProject.WithoutAnUglyTypo/'); done
for i in $(find * -maxdepth 1); do mv $i $(echo $i | sed 's/MyCompanyName\.AbpZeroTemplate/WesternBeef/'); done
```



https://alexanderzeitler.com/articles/rename-visual-studio-project-namespaces-and-folders-automate-everything/