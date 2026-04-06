"use client";

import { useRouter } from "next/navigation";

type Props = {
  category: string;
};

const categories = [
  "A01",
  "A02",
  "A03",
  "A04",
  "A05",
  "A06",
  "A07",
  "A08",
  "A09",
  "A10",
];

export default function CategoryPage({ category }: Props) {
  const router = useRouter();

  const currentIndex = categories.findIndex((c) =>
    category.startsWith(c)
  );

  const goNext = () => {
    if (currentIndex < categories.length - 1) {
      router.push(`/category/${categories[currentIndex + 1]}`);
    }
  };

  const goBack = () => {
    if (currentIndex > 0) {
      router.push(`/category/${categories[currentIndex - 1]}`);
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-6">{category}</h1>

      {/* NAV BUTTONS */}
      <div className="flex justify-between mb-8">
        <button
          onClick={goBack}
          disabled={currentIndex === 0}
          className="px-4 py-2 bg-gray-200 rounded disabled:opacity-50"
        >
          ← Back
        </button>

        <button
          onClick={goNext}
          disabled={currentIndex === categories.length - 1}
          className="px-4 py-2 bg-black text-white rounded disabled:opacity-50"
        >
          Next →
        </button>
      </div>

      {/* CONTENT */}
      <h2 className="font-semibold mb-2">Mitigation Strategies</h2>
      <p className="text-gray-600 mb-6">(Loaded from backend)</p>

      <h2 className="font-semibold mb-2">Vulnerable Lines & Fixes</h2>
      <p className="text-gray-600">No issues found in this category.</p>
    </div>
  );
}
