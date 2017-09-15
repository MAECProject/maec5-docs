//= require ./lib/_energize
//= require ./app/_toc
//= require ./app/_lang

$(function() {
  loadToc($('#toc'), '.toc-link', '.toc-list-h2', 10);
  setupLanguages($('body').data('languages'));
  $('.content').imagesLoaded( function() {
    window.recacheHeights();
    window.refreshToc();
  });

  $('table').each(function(elem) {
    var txt = $(this).find('tr:first-child > td:first-child').text();
    if(txt == 'See common relationships' || txt == 'See common properties') {
      $(this).find('tr:first-child td:not(:first-child)').remove();
      $(this).find('tr:first-child td').attr('colspan', '4');
    }
  })
});

window.onpopstate = function() {
  activateLanguage(getLanguageFromQueryString());
};
