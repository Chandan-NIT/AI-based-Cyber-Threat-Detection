import { BrowserRouter, Routes, Route } from "react-router-dom";

import Home from "./pages/home";
import Stats from "./pages/stats";

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/stats" element={<Stats />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;