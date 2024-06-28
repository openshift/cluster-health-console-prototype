$.noConflict();
jQuery(document).ready(function() {
  window.jQuery = jQuery;
});

function closeAllDetails() {
  const $ = jQuery;
  $(".expand-component").each(function() {
    const icon = $("i", this);
    if (icon.hasClass("fa-angle-down")) {
      const tbody = $(this).parents("tbody");
            details = $(this).parents("tr").next("tr"),
      icon.addClass("fa-angle-right");
      icon.removeClass("fa-angle-down");
      tbody.removeClass("pf-m-expanded");
      details.hide();
    }
  });
}


function registerExpandButtons() {
  // A: One does not simply combine jQuery with Dash/React
  // B: Hold my beer.
  const $ = window.jQuery;

  // clear previous state
  closeAllDetails();
  $(".expand-component").off();

  $(".expand-component").click(function() {
    const icon = $("i", this),
          tbody = $(this).parents("tbody");
          details = $(this).parents("tr").next("tr"),
    icon.toggleClass("fa-angle-down");
    icon.toggleClass("fa-angle-right");
    tbody.toggleClass("pf-m-expanded");
    details.toggle();
  });
}
