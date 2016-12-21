/***********************************************************
*               Validation rules for Search form.          *
*                                                          *
* 1. The text in search input should not be empty and be   *
* all alphanumeric symbols.                                *
* 2. Continent should be selected.                         *
*                                                          *
***********************************************************/
(function(){
  var searchForm =
      document.getElementById('search_form');

      var searchText = document.getElementById("search");
  searchForm.addEventListener('change', function(event){
    var eventTarget = event.target;
    console.log("event.target.className = " + event.target.className);
    var input = event.target;
    var id = input.getAttribute("id");
    var inputText = input.value;
     
    if (inputText.length < 10){
      search.setCustomValidity('Search text must be at least 10 characters long');            
    }else{
      search.setCustomValidity('');
          
    }
     
  })      
   /* add event listenr to schedule form */
  searchForm.addEventListener('submit', function(event) {
  
    event.preventDefault();
   
  })
 
}());
