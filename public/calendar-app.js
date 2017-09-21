$(document).ready(function() {

    // Read a page's GET URL variables and return them as an associative array.
    function getUrlVars() {
        var vars = [],
            hash;
        var hashes = window.location.href.slice(window.location.href.indexOf('?') + 1).split('&');
        for (var i = 0; i < hashes.length; i++) {
            hash = hashes[i].split('=');
            vars.push(hash[0]);
            vars[hash[0]] = hash[1];
        }
        return vars;
    }

    function gotoCurrMonth() {
        var d = new Date();
        currentMonth = d.getMonth() + 1;
        currentYear = d.getFullYear();
    }
    //See if we can get currentMonth an year from query params
    //if not set to todays
    var qParams = getUrlVars();
    var currentMonth = qParams['month'];
    var currentYear = qParams['year'];

    console.log('query currentMonth =' + currentMonth);
    console.log('query currentYear =' + currentYear);

    if (isNaN(parseInt(currentMonth)) || isNaN(parseInt(currentYear))) {
        gotoCurrMonth();
    }

    console.log('currentMonth =' + currentMonth);
    console.log('currentYear =' + currentYear);

    var incMonth = function() {
        currentMonth++;
        if (currentMonth > 12) {
            currentMonth = 1;
            currentYear++;
        }
    };

    var decMonth = function() {
        currentMonth--;
        if (currentMonth < 1) {
            currentMonth = 12;
            currentYear--;
        }
    };

    var getAjaxUrl = function(month, year, user) {
        return '/getcalendar_data?month=' + month + '&year=' + year + '&user=' + user;
    };

    var makeAjaxCall = function(user) {
        $.ajax({
            url: getAjaxUrl(currentMonth, currentYear, user),
            success: function(json_data) {
                $('.responsive-calendar').responsiveCalendar('edit', json_data);
            }
        });
    };
    $('#myschedule').click(function() {
        $('.responsive-calendar').responsiveCalendar('clearAll');
        makeAjaxCall(null);
    });

    $('#prev').click(function() {
        decMonth();
        $('.responsive-calendar').responsiveCalendar('prev');
        makeAjaxCall('all');
    });

    $('#current').click(function() {
        gotoCurrMonth();
        $('.responsive-calendar').responsiveCalendar('curr');
        makeAjaxCall('all');
    });

    $('#next').click(function() {
        incMonth();
        $('.responsive-calendar').responsiveCalendar('next');
        makeAjaxCall('all');
    });

    $(".responsive-calendar").responsiveCalendar({
        time: "" + currentYear + "-" + currentMonth + "",
        onDayClick: function(events) {
            window.location = '/libraryschedule' + '?' + "year=" + $(this).data('year') + "&month=" + $(this).data('month') + "&day=" + $(this).data('day');

        },
        startFromSunday: true,
        activateNonCurrentMonths: true
    });

    makeAjaxCall('all');
});
