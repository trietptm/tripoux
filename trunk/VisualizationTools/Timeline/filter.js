function centerTimeline(date) {
    tl.getBand(0).setCenterVisibleDate(Timeline.DateTime.parseGregorianDateTime(date));
}


var numOfFilters = 4;

function setupFilterHighlightControls(div, timeline, bandIndices, theme) {
   
    // Init Handler
    var handler = function(elmt, evt, target) {
        onKeyPress(timeline, bandIndices, table);
    };
   
   
    // Create Table
    var table = document.createElement("table");
   
    // First Row
    var tr = table.insertRow(0);
    var td = tr.insertCell(0);
    td.innerHTML = "Filters:";
   
      
    // Second Row
    tr = table.insertRow(1);
    tr.style.verticalAlign = "top";
   
    /* Create the text inputs for the filters and add eventListeners */
    for(var i=0; i<numOfFilters; i++) {     
        td = tr.insertCell(i); 
        var input = document.createElement("input");
        input.type = "text";
        SimileAjax.DOM.registerEvent(input, "keypress", handler);
        td.appendChild(input);
        input.id = "filter"+i;     
    }
   
    // Third Row
    tr = table.insertRow(2);
    td = tr.insertCell(0);
      td.innerHTML = "Highlights:";
   
   
    // Fourth Row
       tr = table.insertRow(3);
   
       /* Create the text inputs for the highlights and add event listeners */
       for (var i = 0; i < theme.event.highlightColors.length; i++) {
           td = tr.insertCell(i);
       
           input = document.createElement("input");
           input.type = "text";
           SimileAjax.DOM.registerEvent(input, "keypress", handler);
           td.appendChild(input);
       
        input.id = "highlight"+i;
       
        var divColor = document.createElement("div");
        divColor.style.height = "0.5em";
        divColor.style.background = theme.event.highlightColors[i];
        td.appendChild(divColor);
    }
   
    // Fifth Row
      
    tr = table.insertRow(4);
    td = tr.insertCell(0);
   
    // Append the table to the div
    div.appendChild(table);
}

var numOfFilters = 4;

function setupAntiFilterHighlightControls(div, timeline, bandIndices, theme) {
   
    // Init Handler
    var handler = function(elmt, evt, target) {
        onKeyPressAntiFilter(timeline, bandIndices, table);
    };
   
   
    // Create Table
    var table = document.createElement("table");
   
    // First Row
    var tr = table.insertRow(0);
    var td = tr.insertCell(0);
    td.innerHTML = "Anti-filters:";
   
      
    // Second Row
    tr = table.insertRow(1);
    tr.style.verticalAlign = "top";
   
    /* Create the text inputs for the filters and add eventListeners */
    for(var i=0; i<numOfFilters; i++) {     
        td = tr.insertCell(i); 
        var input = document.createElement("input");
        input.type = "text";
        SimileAjax.DOM.registerEvent(input, "keypress", handler);
        td.appendChild(input);
        input.id = "antifilter"+i;     
    }
      
    tr = table.insertRow(2);
    td = tr.insertCell(0);
   
   
    // Append the table to the div
    div.appendChild(table);
}

var timerID = null;
var filterMatcherGlobal = null;
var antiFilterMatcherGlobal=null;
var highlightMatcherGlobal = null;

function onKeyPress(timeline, bandIndices, table) {
    if (timerID != null) {
        window.clearTimeout(timerID);
    }
    timerID = window.setTimeout(function() {
        performFiltering(timeline, bandIndices, table);
    }, 300);
}

function onKeyPressAntiFilter(timeline, bandIndices, table) {
    if (timerID != null) {
        window.clearTimeout(timerID);
    }
    timerID = window.setTimeout(function() {
        performAntiFiltering(timeline, bandIndices, table);
    }, 300);
}
function cleanString(s) {
    return s.replace(/^\s+/, '').replace(/\s+$/, '');
}

function performFiltering(timeline, bandIndices, table) {
    timerID = null;
    var tr = table.rows[1];
   
    // Add all filter inputs to a new array
    var filterInputs = new Array();
    for(var i=0; i<numOfFilters; i++) {
      filterInputs.push(cleanString(tr.cells[i].firstChild.value));
    }
   
    var filterMatcher = null;
    var filterRegExes = new Array();
    for(var i=0; i<filterInputs.length; i++) {
        /* if the filterInputs are not empty create a new regex for each one and add them
        to an array */
        if (filterInputs[i].length > 0){
                        filterRegExes.push(new RegExp(filterInputs[i], "i"));
        }
                filterMatcher = function(evt) {
                        /* iterate through the regex's and check them against the evtText
                        if match return true, if not found return false */
                        if(filterRegExes.length!=0){
                           
                            for(var j=0; j<filterRegExes.length; j++) {
                                    if(filterRegExes[j].test(evt.getText()) == true){
                                        return true;
                                    }
									// Modification :
									 if(filterRegExes[j].test(evt.getDescription()) == true){
                                        return true;
                                    }
                            }
                        }
                        else if(filterRegExes.length==0){
                            return true;
                        }    
                   return false;
                };
    }
   
    var regexes = [];
    var hasHighlights = false;
    tr=table.rows[3];
    for (var x = 0; x < tr.cells.length; x++) {
        var input = tr.cells[x].firstChild;
        var text2 = cleanString(input.value);
        if (text2.length > 0) {
            hasHighlights = true;
            regexes.push(new RegExp(text2, "i"));
        } else {
            regexes.push(null);
        }
    }
    var highlightMatcher = hasHighlights ? function(evt) {
        var text = evt.getText();
        var description = evt.getDescription();
        for (var x = 0; x < regexes.length; x++) {
            var regex = regexes[x];
            if (regex != null && (regex.test(text) || regex.test(description))) {
            //if (regex != null && regex.test(text)) {
                return x;
            }
        }
        return -1;
    } : null;
   
    // Set the matchers and repaint the timeline
    filterMatcherGlobal = filterMatcher;
    highlightMatcherGlobal = highlightMatcher;   
    for (var i = 0; i < bandIndices.length; i++) {
        var bandIndex = bandIndices[i];
        timeline.getBand(bandIndex).getEventPainter().setFilterMatcher(filterMatcher);
        timeline.getBand(bandIndex).getEventPainter ().setHighlightMatcher(highlightMatcher);
    }
    timeline.paint();
}

function performAntiFiltering(timeline, bandIndices, table) {
    timerID = null;
    var tr = table.rows[1];
   
    // Add all filter inputs to a new array
    var filterInputs = new Array();
    for(var i=0; i<numOfFilters; i++) {
      filterInputs.push(cleanString(tr.cells[i].firstChild.value));
    }
   
    var filterAntiMatcher = null;
    var filterRegExes = new Array();
    for(var i=0; i<filterInputs.length; i++) {
        /* if the filterInputs are not empty create a new regex for each one and add them
        to an array */
        if (filterInputs[i].length > 0){
                        filterRegExes.push(new RegExp(filterInputs[i], "i"));
        }
                filterAntiMatcher = function(evt) {
                        /* iterate through the regex's and check them against the evtText
                        if match return true, if not found return false */
                        if(filterRegExes.length!=0){
                           
                            for(var j=0; j<filterRegExes.length; j++) {
                                    if(filterRegExes[j].test(evt.getText()) == true){
                                        return false;
                                    }
									// Modification :
									 if(filterRegExes[j].test(evt.getDescription()) == true){
                                        return false;
                                    }
                            }
                        }
                        else if(filterRegExes.length==0){
                            return true;
                        }    
                   return true;
                };
    }
   
      
    // Set the matchers and repaint the timeline
    antiFilterMatcherGlobal = filterAntiMatcher;
    for (var i = 0; i < bandIndices.length; i++) {
        var bandIndex = bandIndices[i];
        timeline.getBand(bandIndex).getEventPainter().setFilterMatcher(filterAntiMatcher);
    }
    timeline.paint();
}


function clearAllAntiFilter(timeline, bandIndices, table) {
   
    // First clear the filters
    var tr = table.rows[1];
    for (var x = 0; x < tr.cells.length; x++) {
        tr.cells[x].firstChild.value = "";
    }
   
   
    // Then re-init the filters and repaint the timeline
    for (var i = 0; i < bandIndices.length; i++) {
        var bandIndex = bandIndices[i];
        timeline.getBand(bandIndex).getEventPainter().setFilterMatcher(null);
    }
    timeline.paint();
}


function clearAll(timeline, bandIndices, table) {
   
    // First clear the filters
    var tr = table.rows[1];
    for (var x = 0; x < tr.cells.length; x++) {
        tr.cells[x].firstChild.value = "";
    }
   
    // Then clear the highlights
    var tr = table.rows[3];
    for (var x = 0; x < tr.cells.length; x++) {
        tr.cells[x].firstChild.value = "";
    }
   
    // Then re-init the filters and repaint the timeline
    for (var i = 0; i < bandIndices.length; i++) {
        var bandIndex = bandIndices[i];
        timeline.getBand(bandIndex).getEventPainter().setFilterMatcher(null);
        timeline.getBand(bandIndex).getEventPainter().setHighlightMatcher(null);
    }
    timeline.paint();
}