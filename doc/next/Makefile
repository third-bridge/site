.PHONY: all watch

all:	Site.pdf

Site.pdf:	Introduction.adoc Values.adoc Installation.adoc Authentication.adoc Authorization.adoc AppDevelopment.adoc NextSteps.adoc

%.pdf:	%.adoc
	asciidoctor-pdf \
	-r asciidoctor-diagram \
	-a icons=font \
	-a media=prepress \
	-a pdf-style=juxt \
	-a pdf-fontsdir=fonts \
	-a pdf-style=juxt \
	-a pdf-stylesdir=themes \
	-a sectnumlevels=3 \
	-a sectnums=true \
	-a title-page=true \
	-a xrefstyle=short \
	-o $@ $<

watch:
	find . -name "*.adoc" | entr -n make
